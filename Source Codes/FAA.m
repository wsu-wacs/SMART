%                             Copyright (C) <2017> 
%                        Mahdieh ZabihiMayvan, Reza Sadeghi   
%     Department of Computer Science and Engineering, Kno.e.sis Research Center, 
%                Wright State University, Dayton, OH, USA
% 
%     This program is free software: you can redistribute it and/or modify
%     it under the terms of the GNU General Public License as published by
%     the Free Software Foundation, either version 3 of the License, or
%     any later version.
% 
%     This program is distributed under the License on an "AS IS" BASIS,
%     but WITHOUT ANY WARRANTY; without even the implied warranty of
%     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%     GNU General Public License for more details.
% 
%     You should have received a copy of the GNU General Public License
%     along with this program.  If not, see <http://www.gnu.org/licenses/>.
%
%     Using this code or any associated file of this package in a publication, 
%     please CITE the related paper as below:
%
%     Zabihimayvan, Mahdieh, Reza Sadeghi, H. Nathan Rude, and Derek Doran. 
%     "A Soft Computing Approach for Benign and Malicious Web Robot Detection." 
%     Expert Systems with Applications 87 (2017) 129-140.

%     If you have any questions concerning the implementation of the code, 
%     please feel free to contact us via email addresses below:

%     Zabhimayvan.2@wright.edu, mahdieh@knoesis.org, sadeghi.2@wright.edu,
%     reza@knoesis.org.


% Fuzzy rough feauter selection with greedy algorithm RFFS ->FAA

% Data:Rows->Feauters    Columns->Samples
% Decision-> which numbers are descions ones 
%            in this implication we get just one attribute          

function [OptimalGama,OptimalAttributeType]=FAA(Data,Decision)
%% Data import
%Which attribute is decision?
%Note that Decision in the following code is one attribute!!!
%Decision=16;


x=Data;
SampleNumeber=size(x,2);
FeatureNumber=size(x,1);
%% Functions
%Normalization
normx=x-repmat((min(x'))',1,SampleNumeber);
Input=zeros(size(normx));
for i=1:FeatureNumber
    Divider=max(normx(i,:));
    if(Divider==0),continue,end
    Input(i,:)=normx(i,:)./Divider;
end

%% FAA
OptimalGama=0;
PreviousGama=OptimalGama;

Iteration=FeatureNumber;
AttributeType=-ones(1,FeatureNumber);
AttributeType(1,Decision)=1;
OptimalAttributeType=AttributeType;
OptimalAttributeIteration=OptimalAttributeType;

SelectedFeature=0;
while(true)
    SelectedFeature=SelectedFeature+1;
    for i=1:Iteration
        %Lower calculation
        AttributeType=OptimalAttributeIteration;
        if(i==Decision),continue,end
        AttributeType(i)=0;
        if(sum(AttributeType)==sum(OptimalAttributeIteration)),continue,end
        Lower=LowerCalculation(Input, AttributeType);

        %POS calcultation
        POS=sum(Lower);

        %Dependancy Function
        Gama=POS/SampleNumeber;
            
        if(Gama>OptimalGama)
            OptimalGama=Gama;
            OptimalAttributeType=AttributeType;
        end
    end
    OptimalAttributeIteration=OptimalAttributeType;
    if(OptimalGama-PreviousGama<0.01)
        break
    else
        PreviousGama=OptimalGama;
    end
    if(SelectedFeature==FeatureNumber),break,end
end
%% Results
 disp(OptimalAttributeType)
 disp(OptimalGama)
end
